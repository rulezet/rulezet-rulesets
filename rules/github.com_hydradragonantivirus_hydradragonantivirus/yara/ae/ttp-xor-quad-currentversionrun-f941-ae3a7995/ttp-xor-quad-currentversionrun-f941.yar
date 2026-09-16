rule TTP_XOR_QUAD_CurrentVersionRun_f941 {
  strings:
    $key_f941 = { aa 2e [2] 8e 20 [2] a5 0c [2] 8b 2e [2] 9f 35 [2] 90 2f [2] 8e 32 [2] 8c 33 [2] 97 35 [2] 8b 32 [2] 97 1d }

  condition:
    any of them
}