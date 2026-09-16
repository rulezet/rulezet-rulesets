rule EPWIC_Sum_to_1_hi_filter__flt64___64_big_72_ {
  strings:
    $a0 = { 3f 94 53 71 c8 0f aa ad 3f a6 10 03 42 05 de be bf aa 91 0e 3c 75 de a7 bf d2 c4 4c cb 56 1e 8f 3f e2 0a 9e 47 f8 5e 75 bf d2 c4 4c cb 56 1e 8f bf aa 91 0e 3c 75 de a7 3f a6 10 03 42 05 de be 3f 94 53 71 c8 0f aa ad }

  condition:
    $a0
}