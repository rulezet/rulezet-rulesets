rule TTP_XOR_QUAD_CurrentVersionRun_18fc {
  strings:
    $key_18fc = { 4b 93 [2] 6f 9d [2] 44 b1 [2] 6a 93 [2] 7e 88 [2] 71 92 [2] 6f 8f [2] 6d 8e [2] 76 88 [2] 6a 8f [2] 76 a0 }

  condition:
    any of them
}