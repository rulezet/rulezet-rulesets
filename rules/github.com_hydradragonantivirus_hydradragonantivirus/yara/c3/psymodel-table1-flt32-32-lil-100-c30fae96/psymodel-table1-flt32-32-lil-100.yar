rule psymodel_table1__flt32___32_lil_100_ {
  strings:
    $a0 = { f2 d8 30 41 eb ca 27 41 68 33 1f 41 53 65 10 41 c7 f7 02 41 2a 69 e1 40 fb fa c1 40 d9 ee a6 40 1c a8 8f 40 cc 3f 77 40 55 c6 54 40 3b 1b 37 40 26 93 1d 40 a4 a7 09 40 b8 80 f0 3f 13 c8 db 3f 7f d8 c8 3f e7 50 ba 3f 14 d7 ac 3f 9c c3 a2 3f 00 46 99 3f 21 6d 91 3f 60 fb 89 3f ad e5 84 3f 00 00 80 3f }

  condition:
    $a0
}