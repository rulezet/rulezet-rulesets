rule EPWIC_15_tap_lo_filter__flt64___64_lil_120_ {
  strings:
    $a0 = { d6 e1 b6 a7 7c 70 54 bf 2e 2f a0 9e 95 70 64 bf a8 86 c8 ac 88 e1 81 3f 01 a9 9e e3 db 6f 94 3f 79 c9 ff e4 ef de a9 bf fd ac a6 a9 6d dc be bf 2c 97 95 3f 42 c1 d2 3f 90 46 0d bf fe 98 e6 3f 2c 97 95 3f 42 c1 d2 3f fd ac a6 a9 6d dc be bf 79 c9 ff e4 ef de a9 bf 01 a9 9e e3 db 6f 94 3f a8 86 c8 ac 88 e1 81 3f 2e 2f a0 9e 95 70 64 bf d6 e1 b6 a7 7c 70 54 bf }

  condition:
    $a0
}