rule TTP_XOR_QUAD_CurrentVersionRun_01fc {
  strings:
    $key_01fc = { 52 93 [2] 76 9d [2] 5d b1 [2] 73 93 [2] 67 88 [2] 68 92 [2] 76 8f [2] 74 8e [2] 6f 88 [2] 73 8f [2] 6f a0 }

  condition:
    any of them
}