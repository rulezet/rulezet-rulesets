rule TTP_XOR_QUAD_CurrentVersionRun_26fc {
  strings:
    $key_26fc = { 75 93 [2] 51 9d [2] 7a b1 [2] 54 93 [2] 40 88 [2] 4f 92 [2] 51 8f [2] 53 8e [2] 48 88 [2] 54 8f [2] 48 a0 }

  condition:
    any of them
}