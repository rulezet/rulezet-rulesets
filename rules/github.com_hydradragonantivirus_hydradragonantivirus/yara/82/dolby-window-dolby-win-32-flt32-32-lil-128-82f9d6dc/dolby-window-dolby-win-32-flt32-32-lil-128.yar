rule Dolby_window_dolby_win_32__flt32___32_lil_128_ {
  strings:
    $a0 = { 47 b1 b7 38 46 5d 74 3a 61 77 52 3b 03 ba 04 3c b1 47 8c 3c 02 5e 03 3d 3f 96 60 3d 74 74 b2 3d 5b 6b 05 3e 42 55 3d 3e c8 50 80 3e ee f4 a6 3e 7e 5f d1 3e 0b ec fd 3e 4f 59 15 3f ac de 2a 3f 16 a1 3e 3f a3 eb 4f 3f 93 4c 5e 3f dc 9d 69 3f c7 01 72 3f 84 d4 77 3f 0a 96 7b 3f 59 d1 7d 3f ba 06 7f 3f 69 9d 7f 3f 49 de 7f 3f 64 f6 7f 3f d9 fd 7f 3f a9 ff 7f 3f f9 ff 7f 3f 00 00 80 3f }

  condition:
    $a0
}