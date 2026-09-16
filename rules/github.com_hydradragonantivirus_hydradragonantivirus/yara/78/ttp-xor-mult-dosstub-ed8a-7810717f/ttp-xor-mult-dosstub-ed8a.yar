rule TTP_XOR_MULT_DOSStub_ed8a {
  strings:
    $key_ed8a = { b9 e2 [2] cd fa [2] 8a f8 [2] cd e9 [2] 83 e5 [2] 8f ef [2] 98 e4 [2] 83 aa [2] be }

  condition:
    any of them
}