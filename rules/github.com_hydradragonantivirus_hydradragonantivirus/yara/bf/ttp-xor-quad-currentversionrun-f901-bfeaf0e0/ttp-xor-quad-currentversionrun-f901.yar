rule TTP_XOR_QUAD_CurrentVersionRun_f901 {
  strings:
    $key_f901 = { aa 6e [2] 8e 60 [2] a5 4c [2] 8b 6e [2] 9f 75 [2] 90 6f [2] 8e 72 [2] 8c 73 [2] 97 75 [2] 8b 72 [2] 97 5d }

  condition:
    any of them
}