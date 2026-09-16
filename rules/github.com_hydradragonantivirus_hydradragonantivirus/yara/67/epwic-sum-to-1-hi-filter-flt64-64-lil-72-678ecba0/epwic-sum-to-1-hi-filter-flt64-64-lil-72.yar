rule EPWIC_Sum_to_1_hi_filter__flt64___64_lil_72_ {
  strings:
    $a0 = { ad aa 0f c8 71 53 94 3f be de 05 42 03 10 a6 3f a7 de 75 3c 0e 91 aa bf 8f 1e 56 cb 4c c4 d2 bf 75 5e f8 47 9e 0a e2 3f 8f 1e 56 cb 4c c4 d2 bf a7 de 75 3c 0e 91 aa bf be de 05 42 03 10 a6 3f ad aa 0f c8 71 53 94 3f }

  condition:
    $a0
}