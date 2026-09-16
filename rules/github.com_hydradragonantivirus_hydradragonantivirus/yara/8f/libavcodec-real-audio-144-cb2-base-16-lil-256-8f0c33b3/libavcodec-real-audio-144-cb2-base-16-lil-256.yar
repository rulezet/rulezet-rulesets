rule libavcodec_real_audio_144_cb2_base__16_lil_256_ {
  strings:
    $a0 = { 8e 2f 44 34 37 36 08 36 72 33 ab 33 94 33 15 2f 7a 30 a4 36 0c 38 27 39 2c 33 67 34 a8 33 ec 2f ce 2e 01 36 bb 34 82 37 35 36 c4 39 f3 35 35 33 b9 2c db 33 21 32 95 35 b8 31 80 35 d7 31 75 30 f6 27 99 2f 6c 2d 69 33 f2 2d 92 34 18 30 12 32 cb 28 e5 31 eb 2e c4 36 2a 2e 01 36 a5 30 aa 33 ce 28 6a 33 69 2e dc 37 3b 32 a0 3f b2 34 cd 3a ab 27 14 32 ff 2c 95 36 09 2f e9 3a 5b 31 76 37 76 37 5b 31 e9 3a 09 2f 95 36 ff 2c 14 32 ab 27 cd 3a b2 34 a0 3f 3b 32 dc 37 69 2e 6a 33 ce 28 aa 33 a5 30 01 36 2a 2e c4 36 eb 2e e5 31 cb 28 12 32 18 30 92 34 f2 2d 69 33 6c 2d 99 2f f6 27 75 30 d7 31 80 35 b8 31 95 35 21 32 db 33 b9 2c 35 33 f3 35 c4 39 35 36 82 37 bb 34 01 36 ce 2e ec 2f a8 33 67 34 2c 33 27 39 0c 38 a4 36 7a 30 15 2f 94 33 ab 33 72 33 08 36 37 36 44 34 8e 2f }

  condition:
    $a0
}