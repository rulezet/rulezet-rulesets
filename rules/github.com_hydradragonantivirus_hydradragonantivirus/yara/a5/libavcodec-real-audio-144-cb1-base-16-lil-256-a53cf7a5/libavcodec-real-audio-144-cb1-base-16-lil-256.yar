rule libavcodec_real_audio_144_cb1_base__16_lil_256_ {
  strings:
    $a0 = { c9 4c 2a 48 bd 47 70 44 38 52 37 47 98 48 1f 41 8b 4f 7d 4a d1 4b fe 47 54 55 41 49 9d 4c 03 44 a5 4f 0c 55 a1 4e c6 54 f2 51 f8 4f ab 4c bb 4b e5 53 5e 5a 51 55 6f 5d 49 56 0f 54 8e 52 74 51 db 4c 9d 45 64 4a 45 44 12 4e 3b 42 0e 48 d6 3e 92 52 d3 49 d8 51 f1 49 cc 53 a9 45 88 4e 07 43 3a 4d 58 4e 70 4f 82 51 81 4b 29 47 dc 49 54 46 34 54 bc 55 27 5a 51 5d ba 51 58 4c f8 51 45 4d 45 4d f8 51 58 4c ba 51 51 5d 27 5a bc 55 34 54 54 46 dc 49 29 47 81 4b 82 51 70 4f 58 4e 3a 4d 07 43 88 4e a9 45 cc 53 f1 49 d8 51 d3 49 92 52 d6 3e 0e 48 3b 42 12 4e 45 44 64 4a 9d 45 db 4c 74 51 8e 52 0f 54 49 56 6f 5d 51 55 5e 5a e5 53 bb 4b ab 4c f8 4f f2 51 c6 54 a1 4e 0c 55 a5 4f 03 44 9d 4c 41 49 54 55 fe 47 d1 4b 7d 4a 8b 4f 1f 41 98 48 37 47 38 52 70 44 bd 47 2a 48 c9 4c }

  condition:
    $a0
}