rule TTP_XOR_WriteProcessMemory_ddca {
  strings:
    $key_ddca = { 8a b8 [2] b8 9a [2] be af [2] 90 af [2] af b3 }

  condition:
    any of them
}