rule TTP_XOR_QUAD_CurrentVersionRun_ebe3 {
  strings:
    $key_ebe3 = { b8 8c [2] 9c 82 [2] b7 ae [2] 99 8c [2] 8d 97 [2] 82 8d [2] 9c 90 [2] 9e 91 [2] 85 97 [2] 99 90 [2] 85 bf }

  condition:
    any of them
}