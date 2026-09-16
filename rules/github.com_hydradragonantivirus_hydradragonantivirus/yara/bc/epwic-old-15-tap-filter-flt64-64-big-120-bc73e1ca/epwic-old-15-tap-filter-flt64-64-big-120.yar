rule EPWIC_old_15_tap_filter__flt64___64_big_120_ {
  strings:
    $a0 = { bf 54 17 38 25 24 3a 99 bf 6e 22 cb 73 57 f6 3a 3f 81 94 42 e1 66 54 8f 3f 95 58 e0 cd f2 ae 62 bf a9 be 56 58 89 a6 ba bf bf 12 42 be 1e 55 de 3f d2 bf 3f f2 be 6d 37 3f e6 ab 48 32 fb d3 b4 3f d2 bf 3f f2 be 6d 37 bf bf 12 42 be 1e 55 de bf a9 be 56 58 89 a6 ba 3f 95 58 e0 cd f2 ae 62 3f 81 94 42 e1 66 54 8f bf 6e 22 cb 73 57 f6 3a bf 54 17 38 25 24 3a 99 }

  condition:
    $a0
}