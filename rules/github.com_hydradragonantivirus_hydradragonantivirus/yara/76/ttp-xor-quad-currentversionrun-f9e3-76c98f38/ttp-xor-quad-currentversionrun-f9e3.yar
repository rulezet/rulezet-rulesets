rule TTP_XOR_QUAD_CurrentVersionRun_f9e3 {
  strings:
    $key_f9e3 = { aa 8c [2] 8e 82 [2] a5 ae [2] 8b 8c [2] 9f 97 [2] 90 8d [2] 8e 90 [2] 8c 91 [2] 97 97 [2] 8b 90 [2] 97 bf }

  condition:
    any of them
}