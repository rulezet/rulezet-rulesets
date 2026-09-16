rule PEiD_03403_Vx__Modification_of_Hi_924_ {
  meta:
    description = "[Vx: Modification of Hi.924]"
    ep_only     = "true"

  strings:
    $a = { 50 53 51 52 1E 06 9C B8 21 35 CD 21 53 BB ?? ?? 26 ?? ?? 49 48 5B }

  condition:
    $a
}