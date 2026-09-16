rule PEiD_00042_Ady_s_Glue_1_10_ {
  meta:
    description = "[Ady's Glue 1.10]"
    ep_only     = "true"

  strings:
    $a = { 2E ?? ?? ?? ?? 0E 1F BF ?? ?? 33 DB 33 C0 AC }

  condition:
    $a
}