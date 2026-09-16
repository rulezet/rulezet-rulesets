rule PEiD_03395_Vx__Horse_1776_ {
  meta:
    description = "[Vx: Horse.1776]"
    ep_only     = "true"

  strings:
    $a = { E8 ?? ?? 5D 83 ?? ?? 06 1E 26 ?? ?? ?? ?? BF ?? ?? 1E 0E 1F 8B F7 01 EE B9 ?? ?? FC F3 A6 1F 1E 07 }

  condition:
    $a
}