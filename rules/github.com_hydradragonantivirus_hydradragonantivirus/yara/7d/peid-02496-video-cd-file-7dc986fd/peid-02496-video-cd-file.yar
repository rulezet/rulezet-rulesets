rule PEiD_02496_Video_CD_file_ {
  meta:
    description = "[Video-CD file]"
    ep_only     = "false"

  strings:
    $a = { 52 49 46 46 ?? ?? ?? ?? 43 44 58 41 66 6D 74 }

  condition:
    $a
}