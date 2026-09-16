rule TTP_XOR_QUAD_CurrentVersionRun_3ae3 {
  strings:
    $key_3ae3 = { 69 8c [2] 4d 82 [2] 66 ae [2] 48 8c [2] 5c 97 [2] 53 8d [2] 4d 90 [2] 4f 91 [2] 54 97 [2] 48 90 [2] 54 bf }

  condition:
    any of them
}