rule PEiD_00854_Gardian_Angel_1_0_ {
  meta:
    description = "[Gardian Angel 1.0]"
    ep_only     = "true"

  strings:
    $a = { 06 8C C8 8E D8 8E C0 FC BF ?? ?? EB }

  condition:
    $a
}