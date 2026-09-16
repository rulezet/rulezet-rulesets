rule PEiD_00713_Fish_PE_Shield_1_01____HellFish_ {
  meta:
    description = "[Fish PE Shield 1.01 -> HellFish]"
    ep_only     = "false"

  strings:
    $a = { 55 8B EC 83 C4 D0 53 56 57 8B 45 10 83 C0 0C 8B 00 89 }

  condition:
    $a
}