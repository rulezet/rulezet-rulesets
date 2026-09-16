rule libavcodec_real_audio_144_cb1_base__16_big_256_ {
  strings:
    $a0 = { 4c c9 48 2a 47 bd 44 70 52 38 47 37 48 98 41 1f 4f 8b 4a 7d 4b d1 47 fe 55 54 49 41 4c 9d 44 03 4f a5 55 0c 4e a1 54 c6 51 f2 4f f8 4c ab 4b bb 53 e5 5a 5e 55 51 5d 6f 56 49 54 0f 52 8e 51 74 4c db 45 9d 4a 64 44 45 4e 12 42 3b 48 0e 3e d6 52 92 49 d3 51 d8 49 f1 53 cc 45 a9 4e 88 43 07 4d 3a 4e 58 4f 70 51 82 4b 81 47 29 49 dc 46 54 54 34 55 bc 5a 27 5d 51 51 ba 4c 58 51 f8 4d 45 4d 45 51 f8 4c 58 51 ba 5d 51 5a 27 55 bc 54 34 46 54 49 dc 47 29 4b 81 51 82 4f 70 4e 58 4d 3a 43 07 4e 88 45 a9 53 cc 49 f1 51 d8 49 d3 52 92 3e d6 48 0e 42 3b 4e 12 44 45 4a 64 45 9d 4c db 51 74 52 8e 54 0f 56 49 5d 6f 55 51 5a 5e 53 e5 4b bb 4c ab 4f f8 51 f2 54 c6 4e a1 55 0c 4f a5 44 03 4c 9d 49 41 55 54 47 fe 4b d1 4a 7d 4f 8b 41 1f 48 98 47 37 52 38 44 70 47 bd 48 2a 4c c9 }

  condition:
    $a0
}