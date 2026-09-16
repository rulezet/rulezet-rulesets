import "hash"
rule ccleaner_compromised_installer { 
    meta:
      author = "NVISIO"
      reference = "https://blog.nviso.be/2017/09/21/yara-rules-for-ccleaner-5-33/"
    condition:
        filesize == 9791816 and hash.sha256(0, filesize) == "1a4a5123d7b2c534cb3e3168f7032cf9ebf38b9a2a97226d0fdb7933cf6030ff"
}