rule Empires_Dawn_of_the_modern_World__packets_algorithm__8_byt_256_ {
  strings:
    $a0 = { 00 e7 1a 56 f3 3d 28 13 cf 1f 2e da 5b 80 f2 f3 73 3d 09 ba 4a 7f 33 93 1d b3 3a 90 fc 5c fa 5f 99 c7 f8 af a7 f6 3d bf ec b0 c3 2a 63 1d 48 a9 99 d4 ae f2 bf d2 df 51 7c 23 4d 26 f8 c4 f6 02 4f 97 35 6c c0 d1 05 14 cc cf 2f 80 b4 b8 04 fc 6a cd fb d2 70 e4 04 89 c1 d3 bb 50 39 5c 6a 31 8b 5d fa 46 53 cb c3 89 42 44 58 69 f0 b4 42 db 64 f3 d0 f6 c5 b8 d6 db 56 cf a2 fc 33 07 e4 7b dc a7 df bd 1e ec a1 e0 48 5d 8e 37 5e 7a 08 78 2c 98 75 c3 cf 5a 75 2c c6 ac 85 e2 00 b4 df b9 fc 8d e0 1c 86 43 b1 25 01 f3 87 05 ec 7b 40 4f 8d 96 9b 66 49 db e5 a8 ca 85 4d 80 66 58 ba 0b cc ab 63 70 99 e7 ed a7 b7 69 63 b5 34 32 be 24 7d 4f 5c d3 93 5a 16 c7 40 00 4e 1e ce f0 bc d6 54 2a 33 95 0d f8 38 03 dd a4 a9 f2 74 1e 41 03 18 ad 39 c8 b7 f8 dc 47 2e 48 44 c8 4e 82 17 cd }

  condition:
    $a0
}