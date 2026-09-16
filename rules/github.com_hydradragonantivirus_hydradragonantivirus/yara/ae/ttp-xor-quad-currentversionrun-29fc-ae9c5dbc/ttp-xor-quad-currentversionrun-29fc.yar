rule TTP_XOR_QUAD_CurrentVersionRun_29fc {
  strings:
    $key_29fc = { 7a 93 [2] 5e 9d [2] 75 b1 [2] 5b 93 [2] 4f 88 [2] 40 92 [2] 5e 8f [2] 5c 8e [2] 47 88 [2] 5b 8f [2] 47 a0 }

  condition:
    any of them
}