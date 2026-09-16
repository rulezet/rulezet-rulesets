rule TTP_XOR_QUAD_CurrentVersionRun_f93b {
  strings:
    $key_f93b = { aa 54 [2] 8e 5a [2] a5 76 [2] 8b 54 [2] 9f 4f [2] 90 55 [2] 8e 48 [2] 8c 49 [2] 97 4f [2] 8b 48 [2] 97 67 }

  condition:
    any of them
}