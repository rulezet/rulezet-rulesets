rule CAVE_cave_table__8_byt_256_ {
  strings:
    $a0 = { d9 23 5f e6 ca 68 97 b0 7b f2 0c 34 11 a5 8d 4e 0a 46 77 8d 10 9f 5e 62 f1 34 ec a5 c9 b3 d8 2b 59 47 e3 d2 ff ae 64 ca 15 8b 7d 38 21 bc 96 00 49 56 23 15 97 e4 cb 6f f2 70 3c 88 ba d1 0d ae e2 38 ba 44 9f 83 5d 1c de ab c7 65 f1 76 09 20 86 bd 0a f1 3c a7 29 93 cb 45 5f e8 10 74 62 de b8 77 80 d1 12 26 ac 6d e9 cf f3 54 3a 0b 95 4e b1 30 a4 96 f8 57 49 8e 05 1f 62 7c c3 2b da ed bb 86 0d 7a 97 13 6c 4e 51 30 e5 f2 2f d8 c4 a9 91 76 f0 17 43 38 29 84 a2 db ef 65 5e ca 0d bc e7 fa d8 81 6f 00 14 42 25 7c 5d c9 9e b6 33 ab 5a 6f 9b d9 fe 71 44 c5 37 a2 88 2d 00 b6 13 ec 4e 96 a8 5a b5 d7 c3 8d 3f f2 ec 04 60 71 1b 29 04 79 e3 c7 1b 66 81 4a 25 9d dc 5f 3e b0 f8 a2 91 34 f6 5c 67 89 73 05 22 aa cb ee bf 18 d0 4d f5 36 ae 01 2f 94 c3 49 8b bd 58 12 e0 77 6c da }

  condition:
    $a0
}