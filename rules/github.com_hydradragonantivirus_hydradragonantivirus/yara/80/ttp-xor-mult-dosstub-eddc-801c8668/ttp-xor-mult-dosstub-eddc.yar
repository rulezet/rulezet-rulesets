rule TTP_XOR_MULT_DOSStub_eddc {
  strings:
    $key_eddc = { b9 b4 [2] cd ac [2] 8a ae [2] cd bf [2] 83 b3 [2] 8f b9 [2] 98 b2 [2] 83 fc [2] be }

  condition:
    any of them
}