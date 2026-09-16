rule TTP_XOR_QUAD_CurrentVersionRun_2be3 {
  strings:
    $key_2be3 = { 78 8c [2] 5c 82 [2] 77 ae [2] 59 8c [2] 4d 97 [2] 42 8d [2] 5c 90 [2] 5e 91 [2] 45 97 [2] 59 90 [2] 45 bf }

  condition:
    any of them
}