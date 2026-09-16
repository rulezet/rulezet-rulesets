rule TTP_XOR_QUAD_CurrentVersionRun_f6e3 {
  strings:
    $key_f6e3 = { a5 8c [2] 81 82 [2] aa ae [2] 84 8c [2] 90 97 [2] 9f 8d [2] 81 90 [2] 83 91 [2] 98 97 [2] 84 90 [2] 98 bf }

  condition:
    any of them
}