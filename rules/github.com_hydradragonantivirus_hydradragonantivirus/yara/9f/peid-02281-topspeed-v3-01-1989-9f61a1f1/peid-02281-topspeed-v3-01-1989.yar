rule PEiD_02281_TopSpeed_v3_01_1989_ {
  meta:
    description = "[TopSpeed v3.01 1989]"
    ep_only     = "true"

  strings:
    $a = { 1E BA ?? ?? 8E DA 8B ?? ?? ?? 8B ?? ?? ?? FF ?? ?? ?? 50 53 }

  condition:
    $a
}