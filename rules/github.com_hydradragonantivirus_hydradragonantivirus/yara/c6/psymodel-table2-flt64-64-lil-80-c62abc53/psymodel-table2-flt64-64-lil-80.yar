rule psymodel_table2__flt64___64_lil_80_ {
  strings:
    $a0 = { 00 00 00 20 d1 73 fc 3f 00 00 00 a0 7c 8a fd 3f 00 00 00 e0 d4 ab fe 3f 00 00 00 60 93 22 ff 3f 00 00 00 c0 21 9b ff 3f 00 00 00 60 ef 51 fd 3f 00 00 00 40 fb 32 fb 3f 00 00 00 40 9c f0 f7 3f 00 00 00 80 2f 12 f5 3f 00 00 00 00 00 00 f0 3f }

  condition:
    $a0
}