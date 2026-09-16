rule TTP_XOR_QUAD_CurrentVersionRun_e33d {
  strings:
    $key_e33d = { b0 52 [2] 94 5c [2] bf 70 [2] 91 52 [2] 85 49 [2] 8a 53 [2] 94 4e [2] 96 4f [2] 8d 49 [2] 91 4e [2] 8d 61 }

  condition:
    any of them
}