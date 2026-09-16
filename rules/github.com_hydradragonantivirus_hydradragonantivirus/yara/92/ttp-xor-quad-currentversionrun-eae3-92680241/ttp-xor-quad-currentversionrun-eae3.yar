rule TTP_XOR_QUAD_CurrentVersionRun_eae3 {
  strings:
    $key_eae3 = { b9 8c [2] 9d 82 [2] b6 ae [2] 98 8c [2] 8c 97 [2] 83 8d [2] 9d 90 [2] 9f 91 [2] 84 97 [2] 98 90 [2] 84 bf }

  condition:
    any of them
}