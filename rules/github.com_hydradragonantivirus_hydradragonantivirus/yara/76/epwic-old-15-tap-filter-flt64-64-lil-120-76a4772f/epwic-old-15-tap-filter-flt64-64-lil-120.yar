rule EPWIC_old_15_tap_filter__flt64___64_lil_120_ {
  strings:
    $a0 = { 99 3a 24 25 38 17 54 bf 3a f6 57 73 cb 22 6e bf 8f 54 66 e1 42 94 81 3f 62 ae f2 cd e0 58 95 3f ba a6 89 58 56 be a9 bf de 55 1e be 42 12 bf bf 37 6d be f2 3f bf d2 3f b4 d3 fb 32 48 ab e6 3f 37 6d be f2 3f bf d2 3f de 55 1e be 42 12 bf bf ba a6 89 58 56 be a9 bf 62 ae f2 cd e0 58 95 3f 8f 54 66 e1 42 94 81 3f 3a f6 57 73 cb 22 6e bf 99 3a 24 25 38 17 54 bf }

  condition:
    $a0
}