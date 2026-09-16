rule TTP_XOR_QUAD_CurrentVersionRun_33fc {
  strings:
    $key_33fc = { 60 93 [2] 44 9d [2] 6f b1 [2] 41 93 [2] 55 88 [2] 5a 92 [2] 44 8f [2] 46 8e [2] 5d 88 [2] 41 8f [2] 5d a0 }

  condition:
    any of them
}