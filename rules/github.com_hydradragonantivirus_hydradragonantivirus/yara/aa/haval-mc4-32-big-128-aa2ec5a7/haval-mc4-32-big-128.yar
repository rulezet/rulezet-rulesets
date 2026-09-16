rule Haval_mc4__32_big_128_ {
  strings:
    $a0 = { 7a 32 53 81 28 95 86 77 3b 8f 48 98 6b 4b b9 af c4 bf e8 1b 66 28 21 93 61 d8 09 cc fb 21 a9 91 48 7c ac 60 5d ec 80 32 ef 84 5d 5d e9 85 75 b1 dc 26 23 02 eb 65 1b 88 23 89 3e 81 d3 96 ac c5 0f 6d 6f f3 83 f4 42 39 2e 0b 44 82 a4 84 20 04 69 c8 f0 4a 9e 1f 9b 5e 21 c6 68 42 f6 e9 6c 9a 67 0c 9c 61 ab d3 88 f0 6a 51 a0 d2 d8 54 2f 68 96 0f a7 28 ab 51 33 a3 6e ef 0b 6c 13 7a 3b e4 }

  condition:
    $a0
}