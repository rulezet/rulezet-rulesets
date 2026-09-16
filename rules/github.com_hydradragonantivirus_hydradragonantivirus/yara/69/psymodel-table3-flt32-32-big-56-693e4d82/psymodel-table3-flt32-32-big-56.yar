rule psymodel_table3__flt32___32_big_56_ {
  strings:
    $a0 = { 40 b1 44 94 40 a8 30 e6 40 9f 94 70 40 90 bc f4 40 83 47 40 40 61 f2 54 40 42 71 1c 40 27 54 6a 40 0f ff 82 3f f7 d5 f2 3f d5 47 6c 3f b7 8a 61 3f 9d f2 95 3f 89 fb 60 }

  condition:
    $a0
}