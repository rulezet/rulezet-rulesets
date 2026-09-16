rule TTP_XOR_QUAD_CurrentVersionRun_f921 {
  strings:
    $key_f921 = { aa 4e [2] 8e 40 [2] a5 6c [2] 8b 4e [2] 9f 55 [2] 90 4f [2] 8e 52 [2] 8c 53 [2] 97 55 [2] 8b 52 [2] 97 7d }

  condition:
    any of them
}