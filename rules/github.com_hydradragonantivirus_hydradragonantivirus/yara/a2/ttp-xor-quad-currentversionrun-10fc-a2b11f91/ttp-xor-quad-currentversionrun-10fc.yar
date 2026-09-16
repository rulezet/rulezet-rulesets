rule TTP_XOR_QUAD_CurrentVersionRun_10fc {
  strings:
    $key_10fc = { 43 93 [2] 67 9d [2] 4c b1 [2] 62 93 [2] 76 88 [2] 79 92 [2] 67 8f [2] 65 8e [2] 7e 88 [2] 62 8f [2] 7e a0 }

  condition:
    any of them
}