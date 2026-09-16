import "hash"
rule Dotclear: Blog {
  condition:
    
    hash.sha1(0, filesize) == "c732d2d54a80250fb8b51d4dddb74d05a59cee2e" or      hash.sha1(0, filesize) == "cc494f7f4044b5a3361281e27f2f7bb8952b8964" or  
    
    hash.sha1(0, filesize) == "192126b08c40c5ca086b5e4d7433e982f708baf3" or      hash.sha1(0, filesize) == "51e6810ccd3773e2bd453e97ccf16059551bae08" or      hash.sha1(0, filesize) == "4172e35e7c9ce35de9f56fb8dfebe8d453f0dee4" or      hash.sha1(0, filesize) == "cf65db6ae55486f51370f87c4653aaed56903ccc"  }