rule TTP_XOR_QUAD_CurrentVersionRun_09fc {
  strings:
    $key_09fc = { 5a 93 [2] 7e 9d [2] 55 b1 [2] 7b 93 [2] 6f 88 [2] 60 92 [2] 7e 8f [2] 7c 8e [2] 67 88 [2] 7b 8f [2] 67 a0 }

  condition:
    any of them
}