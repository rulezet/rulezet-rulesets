rule TTP_XOR_WriteProcessMemory_921f {
  strings:
    $key_921f = { c5 6d [2] f7 4f [2] f1 7a [2] df 7a [2] e0 66 }

  condition:
    any of them
}