rule PEiD_03494_WWPack32_v1_x_ {
  meta:
    description = "[WWPack32 v1.x]"
    ep_only     = "true"

  strings:
    $a = { 53 55 8B E8 33 DB EB 60 }

  condition:
    $a
}