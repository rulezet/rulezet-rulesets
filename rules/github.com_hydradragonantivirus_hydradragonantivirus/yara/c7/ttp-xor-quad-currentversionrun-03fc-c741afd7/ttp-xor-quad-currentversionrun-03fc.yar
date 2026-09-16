rule TTP_XOR_QUAD_CurrentVersionRun_03fc {
  strings:
    $key_03fc = { 50 93 [2] 74 9d [2] 5f b1 [2] 71 93 [2] 65 88 [2] 6a 92 [2] 74 8f [2] 76 8e [2] 6d 88 [2] 71 8f [2] 6d a0 }

  condition:
    any of them
}