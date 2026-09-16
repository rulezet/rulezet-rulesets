rule TTP_XOR_QUAD_CurrentVersionRun_e0fc {
  strings:
    $key_e0fc = { b3 93 [2] 97 9d [2] bc b1 [2] 92 93 [2] 86 88 [2] 89 92 [2] 97 8f [2] 95 8e [2] 8e 88 [2] 92 8f [2] 8e a0 }

  condition:
    any of them
}