rule TTP_XOR_WriteProcessMemory_921e {
  strings:
    $key_921e = { c5 6c [2] f7 4e [2] f1 7b [2] df 7b [2] e0 67 }

  condition:
    any of them
}