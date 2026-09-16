rule Ultima_Online_uodemo_dat_algorithm_key__32_big_32_ {
  strings:
    $a0 = { f7 aa 4c 98 bf 62 c0 67 0b 52 43 34 bc 28 a2 d0 6b 57 c2 d1 23 38 43 aa c0 6d 02 10 38 d4 f8 04 }

  condition:
    $a0
}