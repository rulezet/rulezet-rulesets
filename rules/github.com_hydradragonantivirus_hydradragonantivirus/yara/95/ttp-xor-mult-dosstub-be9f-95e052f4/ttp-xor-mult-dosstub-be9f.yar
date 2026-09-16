rule TTP_XOR_MULT_DOSStub_be9f {
  strings:
    $key_be9f = { ea f7 [2] 9e ef [2] d9 ed [2] 9e fc [2] d0 f0 [2] dc fa [2] cb f1 [2] d0 bf [2] ed }

  condition:
    any of them
}