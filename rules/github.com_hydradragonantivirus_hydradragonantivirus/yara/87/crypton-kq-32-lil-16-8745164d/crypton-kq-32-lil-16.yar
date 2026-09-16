rule Crypton_kq__32_lil_16_ {
  strings:
    $a0 = { 8c 68 05 9b ab d9 83 1f 19 cd e0 5b 5d 9d bb cb }

  condition:
    $a0
}